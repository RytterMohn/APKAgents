"""
APK Multi-Agent Analyzer
APK多Agent分析系统入口
"""

import os
import sys
import argparse
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from agents import OrchestratorAgent, AgentContext
from utils import Config, Logger, get_apk_name, create_task_dir
from utils.exceptions import AgentError


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="APK Multi-Agent Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py app.apk
  python main.py app.apk -o output
  python main.py app.apk --config config.yaml
  python main.py app.apk --no-decompile
        """
    )

    parser.add_argument(
        "apk",
        help="APK文件路径"
    )

    parser.add_argument(
        "-o", "--output",
        default="output",
        help="输出目录 (默认: output)"
    )

    parser.add_argument(
        "-c", "--config",
        default="config/default.yaml",
        help="配置文件路径 (默认: config/default.yaml)"
    )

    parser.add_argument(
        "--no-decompile",
        action="store_true",
        help="跳过反编译步骤"
    )

    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="跳过漏洞扫描"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出"
    )

    return parser.parse_args()


def main():
    """主函数"""
    args = parse_args()

    # 验证APK文件
    if not os.path.exists(args.apk):
        print(f"错误: APK文件不存在: {args.apk}")
        sys.exit(1)

    # 初始化日志
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = Logger("APKAnalyzer", level=log_level).get_logger()

    logger.info(f"APK文件: {args.apk}")
    logger.info(f"输出目录: {args.output}")

    # 加载配置
    config = Config()
    if os.path.exists(args.config):
        config.load(args.config)
        logger.info(f"配置文件: {args.config}")
    else:
        logger.warning(f"配置文件不存在: {args.config}，使用默认配置")

    # 根据命令行参数修改配置
    if args.no_decompile:
        config.set("agents.enabled.decompiler", False)
    if args.no_scan:
        config.set("agents.enabled.scanner", False)

    # 创建任务目录
    apk_name = get_apk_name(args.apk)
    task_dir = create_task_dir(args.output, apk_name)
    logger.info(f"任务目录: {task_dir}")

    # 创建Agent Context
    context = AgentContext(
        apk_path=os.path.abspath(args.apk),
        output_dir=task_dir,
        config=config.data
    )

    # 执行分析
    try:
        agent = OrchestratorAgent(config.data.get("agents", {}))
        result = agent.execute(context)

        if result.success:
            logger.info("=" * 50)
            logger.info("分析完成!")
            logger.info("=" * 50)
            logger.info(f"任务ID: {context.task_id}")
            logger.info(f"执行时长: {context.get_duration():.2f}秒")

            if context.errors:
                logger.warning(f"警告: {len(context.errors)}个错误")

            # 输出报告路径
            if context.markdown_report:
                logger.info(f"Markdown报告: {context.markdown_report}")
            if context.html_report:
                logger.info(f"HTML报告: {context.html_report}")
            if context.json_report:
                logger.info(f"JSON报告: {context.json_report}")

            # 输出风险等级
            if context.risk_level:
                logger.info(f"风险等级: {context.risk_level.upper()}")
                if context.risk_score:
                    logger.info(f"风险评分: {context.risk_score}")

            # 输出漏洞数量
            if context.vulnerabilities:
                logger.info(f"发现漏洞: {len(context.vulnerabilities)}个")

            return 0
        else:
            logger.error("分析失败!")
            for error in result.errors:
                logger.error(f"  - {error}")
            return 1

    except KeyboardInterrupt:
        logger.warning("分析被用户中断")
        return 130
    except Exception as e:
        logger.error(f"分析异常: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())